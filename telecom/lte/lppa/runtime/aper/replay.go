// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/replay.go; SHA-256 61436b8c7f64110640046030244e1ded74db504599039944df13584f0bb16705.
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
	resources  []replayResources
	data       []byte
	nodes      int
	original   []byte
	budget     DecodeBudget
	report     DecodeReport
	buffers    []BitBuffer
	nextBuffer int
	scalars    []int64
	nextScalar int
	opaque     *OpaqueOpenType
}
type SemanticFrame struct {
	start       int
	resources   replayResources
	ownDepth    uint64
	countsKnown bool
}

// ComparisonFrame carries only the read cursor and enclosing comparison state.
// Capture's resource accumulation does not belong on each comparison frame.
type ComparisonFrame struct {
	start, end, limit int
	valueDepth        int
	changed           bool
}

// SemanticCapture records immutable semantics once after a successful decode.
// Its write-capable API is separate from comparison to keep encoding read-only.
type SemanticCapture struct {
	owner       *semanticArena
	resources   replayResources
	ownDepth    uint64
	countsKnown bool
}

func NewSemanticCapture(hint int) SemanticCapture {
	if hint < 256 {
		hint = 256
	}
	return SemanticCapture{owner: &semanticArena{data: make([]byte, 0, hint)}}
}
func (s *SemanticCapture) Begin() SemanticFrame {
	f := SemanticFrame{start: len(s.owner.data), resources: s.resources, ownDepth: s.ownDepth, countsKnown: s.countsKnown}
	s.resources = replayResources{}
	s.ownDepth = 0
	s.countsKnown = false
	s.fixed(make([]byte, 8))
	return f
}
func (s *SemanticCapture) End(f SemanticFrame, node *Snapshot, _ bool) {
	if len(s.owner.data)-f.start < 8 {
		return
	}
	binary.LittleEndian.PutUint64(s.owner.data[f.start:f.start+8], uint64(len(s.owner.data)-f.start-8))
	if node != nil {
		*node = Snapshot{owner: s.owner, start: f.start, end: len(s.owner.data), node: s.owner.nodes}
		if len(s.owner.resources) < cap(s.owner.resources) {
			if s.owner.budget.operational.MaxAllocatedBytes != 0 {
				if err := NewBudgetBuffer(&s.owner.budget).ChargeWork(uint64(unsafe.Sizeof(replayResources{}))); err != nil {
					return
				}
			}
			n := len(s.owner.resources)
			s.owner.resources = s.owner.resources[:n+1]
			s.owner.resources[n] = s.resources
		} else if s.owner.budget.operational.MaxAllocatedBytes != 0 {
			next, err := AppendValues(NewBudgetBuffer(&s.owner.budget), s.owner.resources, s.resources)
			if err == nil {
				s.owner.resources = next
			}
		} else {
			s.owner.resources = append(s.owner.resources, s.resources)
		}
		s.owner.nodes++
	}
	child := s.resources
	s.resources = f.resources
	s.ownDepth = f.ownDepth
	s.countsKnown = f.countsKnown
	s.resources.depth = max(s.resources.depth, s.ownDepth+child.depth)
	s.resources.open = max(s.resources.open, child.open)
	if !s.countsKnown {
		s.resources.elements += child.elements
		s.resources.fragments += child.fragments
	}
}
func (s *SemanticCapture) fixed(data []byte) {
	if len(data) <= cap(s.owner.data)-len(s.owner.data) {
		if s.owner.budget.operational.MaxAllocatedBytes != 0 {
			if err := NewBudgetBuffer(&s.owner.budget).ChargeWork(uint64(len(data))); err != nil {
				return
			}
		}
		start := len(s.owner.data)
		s.owner.data = s.owner.data[:start+len(data)]
		copy(s.owner.data[start:], data)
	} else if s.owner.budget.operational.MaxAllocatedBytes != 0 {
		next, err := AppendValues(NewBudgetBuffer(&s.owner.budget), s.owner.data, data...)
		if err != nil {
			return
		}
		s.owner.data = next
	} else {
		s.owner.data = append(s.owner.data, data...)
	}
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
		s.Uint(uint64(word))
	}
}
func (s *SemanticCapture) Opaque(value OpaqueOpenType) {
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
		s.OpenBytes(OpaqueOpenType{bytes: value.contents, image: value.image}.ContentLength())
		s.Opaque(OpaqueOpenType{bytes: value.contents, image: value.image})
	}
}

// ReplayPlan is a by-value decision result. Its inline states never point back
// into a caller's stack, so an unchanged encode needs only its returned bytes.
// Large trees use one bounded overflow slice; no state is retained in values.
type ReplayPlan struct {
	limits                     ComparisonLimits
	work, allocation, elements uint64
	failure                    string
	root                       Snapshot
	states                     [64]uint8
	extra                      []uint8
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
		size := (p.root.owner.nodes-1)/8 + 1 - len(p.states)
		if p.limits.limited && uint64(size) > p.limits.Allocated {
			p.failure = "comparison allocation exceeded"
			return
		}
		p.allocation = uint64(size)
		p.extra = make([]uint8, size)
	}
	if p.failure != "" {
		return
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
	valueDepth int
}

func NewSemanticComparison(root Snapshot, limits ...ComparisonLimits) SemanticComparison {
	s := SemanticComparison{plan: ReplayPlan{root: root}, pos: root.start, limit: root.end}
	if len(limits) > 0 {
		s.plan.limits = limits[0]
	}

	return s
}
func (s *SemanticComparison) Plan() ReplayPlan { return s.plan }
func (s *SemanticComparison) Begin() (f ComparisonFrame) {
	f.start, f.limit, f.changed, f.valueDepth = s.pos, s.limit, s.changed, s.valueDepth
	f.end = s.beginFrame()
	return
}
func (s *SemanticComparison) beginFrame() int {
	s.charge(1)
	s.changed = false
	if s.pos <= s.limit-8 {
		n := binary.LittleEndian.Uint64(s.plan.root.owner.data[s.pos : s.pos+8])
		s.pos += 8
		if n <= uint64(s.limit-s.pos) {
			s.limit = s.pos + int(n)
		} else {
			s.changed = true
		}
	} else {
		s.changed = true
	}
	return s.limit
}
func (s *SemanticComparison) End(f ComparisonFrame, node Snapshot, fresh bool) {
	s.valueDepth = f.valueDepth
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
	s.charge(uint64(len(data)))
	if s.Failed() {
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
	s.charge(8)
	if s.Failed() {
		return
	}
	if s.pos > s.limit-8 {
		s.changed = true
		s.pos = s.limit
		return
	}
	if binary.LittleEndian.Uint64(s.plan.root.owner.data[s.pos:s.pos+8]) != value {
		s.changed = true
	}
	s.pos += 8
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
	n := s.length()
	if n != len(value) {
		s.changed = true
	}
	if n < 0 || n > s.limit-s.pos {
		s.changed = true
		s.pos = s.limit
		return
	}
	s.charge(uint64(min(len(value), n)))
	if s.Failed() {
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
	n := s.length()
	if n < 0 || n > s.limit-s.pos {
		s.changed = true
		s.pos = s.limit
		return
	}
	s.charge(uint64(min(len(value), n)))
	if s.Failed() {
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
type minimalDecodeOwner struct {
	resources [4]replayResources
	arena     semanticArena
	original  [16]byte
	semantics [128]byte
	buffers   [2]BitBuffer
}
type smallDecodeOwner struct {
	resources [7]replayResources
	arena     semanticArena
	original  [16]byte
	semantics [224]byte
	buffers   [3]BitBuffer
}
type opaqueDecodeOwner struct {
	resources [7]replayResources
	arena     semanticArena
	original  [16]byte
	semantics [224]byte
	buffers   [3]BitBuffer
	scalars   [1]int64
	opaque    OpaqueOpenType
}
type messageDecodeOwner struct {
	resources [8]replayResources
	arena     semanticArena
	original  [24]byte
	semantics [288]byte
	buffers   [4]BitBuffer
	scalars   [1]int64
}

func newSemanticOwner(data []byte) *semanticArena {
	var owner *semanticArena
	if len(data) <= 9 {
		p := new(minimalDecodeOwner)
		owner = &p.arena
		owner.original = append(p.original[:0], data...)
		owner.data = p.semantics[:0]
		owner.resources = p.resources[:0]
		owner.buffers = p.buffers[:]
	} else if len(data) <= 14 {
		p := new(smallDecodeOwner)
		owner = &p.arena
		owner.original = append(p.original[:0], data...)
		owner.data = p.semantics[:0]
		owner.resources = p.resources[:0]
		owner.buffers = p.buffers[:]
	} else if len(data) <= 16 {
		p := new(opaqueDecodeOwner)
		owner = &p.arena
		owner.original = append(p.original[:0], data...)
		owner.data = p.semantics[:0]
		owner.resources = p.resources[:0]
		owner.buffers = p.buffers[:]
		owner.scalars = p.scalars[:]
		owner.opaque = &p.opaque
	} else {
		p := new(messageDecodeOwner)
		owner = &p.arena
		owner.original = append(p.original[:0], data...)
		owner.data = p.semantics[:0]
		owner.resources = p.resources[:0]
		owner.buffers = p.buffers[:]
		owner.scalars = p.scalars[:]
	}
	owner.budget.owner = owner
	return owner
}

func NewCompleteDecodeBuffer(data []byte, options DecodeState) *BitBuffer {
	if decodeOwner(options) == nil {
		return NewBitBufferFromBytes(data)
	}
	return decodeOwner(options).buffer(data, nil)
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
	if o.nextBuffer < len(o.buffers) {
		bb = &o.buffers[o.nextBuffer]
		o.nextBuffer++
	} else {
		reservation := parent
		if reservation == nil {
			reservation = &o.buffers[0]
		}
		if err := ChargeValue(reservation, BitBuffer{}); err != nil {
			// The shared budget is terminal. Reuse an existing failed reader
			// without changing its cursor or allocating failure-only storage.
			return reservation
		}
		bb = new(BitBuffer)
	}
	*bb = BitBuffer{data: data, budget: &o.budget}
	if len(data) > int(^uint(0)>>1)/8 {
		bb.invalidLength = true
	} else {
		bb.bitLen = len(data) * 8
	}
	if parent != nil {
		bb.nested = true
		bb.trace = parent.trace

	}
	return bb
}
func SemanticCaptureFor(options DecodeState) SemanticCapture {
	if decodeOwner(options) == nil {
		return NewSemanticCapture(256)
	}
	return SemanticCapture{owner: decodeOwner(options)}
}
func (bb *BitBuffer) ownsInput() bool { return bb.budget != nil && bb.budget.owner != nil }

// OwnInt64 supplies mutable source scalar storage from the decode's owner.
// After its small inline capacity, each additional scalar has its own storage.
func (bb *BitBuffer) OwnInt64(value int64) *int64 {
	if bb.ownsInput() {
		o := bb.budget.owner
		if o.nextScalar < len(o.scalars) {
			p := &o.scalars[o.nextScalar]
			o.nextScalar++
			*p = value
			return p
		}
	}
	if err := bb.ChargeAllocation(1, 8); err != nil {
		return nil
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
			s.OpenBytes(uint64(len(data[i])))
			s.Bytes(data[i])
		} else if i < len(spans) && spans[i].Present() {
			s.Uint(uint64(i))
			s.OpenBytes(uint64(spans[i].Len()))
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

// SetReplayPlan attaches one comparison result to the existing operation scope.
func (b *DecodeBudget) SetReplayPlan(plan *ReplayPlan) { b.encodePlan = plan }
func decodeOwner(state DecodeState) *semanticArena {
	if state.settings.operation == nil {
		return nil
	}
	return state.settings.operation.owner
}

// OwnDecodeInputOptions allocates one immutable input owner before parsing.
// The caller's options remain reusable; all counters belong to this call.
func OwnDecodeInputOptions(data []byte, options ...DecodeOption) ([]byte, DecodeState) {
	var limits Limits
	for _, option := range options {
		if option.hasLimits {
			limits = option.limits
		}
	}
	// Decode ignores the encode-only ceiling, as ApplyDecodeOptions does.
	limits.MaxOutputBytes = 0
	var budget DecodeBudget
	if err := initOperationBudget(&budget, limits); err != nil {
		return nil, DecodeState{failure: err}
	}
	for _, option := range options {
		budget.nonzeroTerminalPadding = budget.nonzeroTerminalPadding || option.nonzeroTerminalPadding
	}
	budget.reading = true
	budget.outputLimited = false
	if uint64(len(data)) > budget.operational.MaxInputBytes {
		return nil, DecodeState{failure: NewBudgetBuffer(&budget).resourceError("input bytes exceeded")}
	}
	return ownDecodeInputBudget(data, budget)
}
func ownDecodeInputBudget(data []byte, budget DecodeBudget) ([]byte, DecodeState) {
	bb := NewBudgetBuffer(&budget)
	size := uint64(unsafe.Sizeof(messageDecodeOwner{}))
	capacity := 24
	if len(data) <= 9 {
		size = uint64(unsafe.Sizeof(minimalDecodeOwner{}))
		capacity = 16
	} else if len(data) <= 14 {
		size = uint64(unsafe.Sizeof(smallDecodeOwner{}))
		capacity = 16
	} else if len(data) <= 16 {
		size = uint64(unsafe.Sizeof(opaqueDecodeOwner{}))
		capacity = 16
	}
	if err := bb.ChargeAllocation(1, size); err != nil {
		return nil, DecodeState{failure: err}
	}
	if len(data) > capacity {
		if err := bb.ChargeAllocation(uint64(len(data)), 1); err != nil {
			return nil, DecodeState{failure: err}
		}
	}
	owner := newSemanticOwner(data)
	owner.budget = budget
	owner.budget.owner = owner
	owner.budget.callReport = &owner.report
	state := DecodeState{settings: decodeSettings{operation: &owner.budget, callReport: &owner.report}}
	return owner.original, state
}

// OwnDecodeInput preserves state for internal complete-codec entry points.
func OwnDecodeInput(data []byte, state DecodeState) ([]byte, DecodeState) {
	if state.failure != nil {
		return nil, state
	}
	if decodeOwner(state) != nil {
		return data, state
	}
	if state.settings.operation != nil {
		return ownDecodeInputBudget(data, *state.settings.operation)
	}
	return OwnDecodeInputOptions(data)
}

// ReplayBytes copies a received form under the same operation limits as encoding.
func (s WireSpan) ReplayBytes(budget *DecodeBudget) ([]byte, error) {
	bb := NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(s.Len()), 1); err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(s.Len())); err != nil {
		return nil, err
	}
	return s.bytes()
}

// replayResources describes the source operations skipped by a span replay.
// It never contains a PER baseline and never participates in semantic equality.
type replayResources struct{ depth, open, elements, fragments uint64 }

func (s *SemanticCapture) Value() { s.ownDepth = 1; s.resources.depth = max(s.resources.depth, 1) }
func (s *SemanticCapture) Stream(span WireSpan) {
	if span.Present() {
		s.resources.elements = span.elements
		s.resources.fragments = span.fragments
		s.countsKnown = true
	}
}
func (s *SemanticCapture) Elements(n uint64) {
	if !s.countsKnown {
		s.resources.elements += n
	}
}
func (s *SemanticCapture) OpenBytes(n uint64) { s.resources.open = max(s.resources.open, n) }
func (s *SemanticCapture) OperationCounts() {
	s.resources.elements = s.owner.budget.usage.Elements
	s.resources.fragments = s.owner.budget.fragments
	s.countsKnown = true
}
func (s *SemanticComparison) Value() {
	s.valueDepth++
	if s.plan.limits.limited && s.valueDepth > s.plan.limits.Depth {
		s.plan.failure = "PER nesting depth exceeded during comparison"
	}
}
func (s *SemanticComparison) Stream(WireSpan) {}
func (s *SemanticComparison) Elements(n uint64) {
	if s.plan.limits.limited && n > s.plan.limits.Elements-s.plan.elements {
		s.plan.failure = "elements exceeded during comparison"
		return
	}
	s.plan.elements += n
}
func (s *SemanticComparison) OpenBytes(uint64) {}

// ApplyReplay preserves every structural operation ceiling while skipping encoders.
func (s Snapshot) ApplyReplay(budget *DecodeBudget) error {
	if s.owner == nil || s.node < 0 || s.node >= len(s.owner.resources) {
		return ErrInvalidValue
	}
	r := s.owner.resources[s.node]
	bb := NewBudgetBuffer(budget)
	if r.depth > uint64(budget.limits.MaxDepth-budget.depth) {
		return bb.resourceError("PER nesting depth exceeded during replay")
	}
	budget.usage.MaxDepth = max(budget.usage.MaxDepth, budget.depth+int(r.depth))
	if budget.operational.MaxOpenTypeBytes != 0 && r.open > budget.operational.MaxOpenTypeBytes {
		return bb.resourceError("open type bytes exceeded during replay")
	}
	if err := bb.ChargeElements(int64(r.elements)); err != nil {
		return err
	}
	if budget.operational.MaxFragments != 0 && r.fragments > budget.operational.MaxFragments-budget.fragments {
		return bb.resourceError("fragments exceeded during replay")
	}
	if err := bb.ChargeWork(r.fragments); err != nil {
		return err
	}
	budget.fragments += r.fragments
	return nil
}
func (s Snapshot) ReplayTo(span WireSpan, bb *BitBuffer) (bool, error) {
	// Alignment refusal must not charge an operation which will encode normally.
	if !span.compatibleAlignment(bb) {
		return false, nil
	}
	if err := s.ApplyReplay(bb.Budget()); err != nil {
		return false, err
	}
	return span.ReplayTo(bb)
}

func (s *SemanticCapture) Failed() bool    { return s.owner.budget.err != nil }
func (s *SemanticComparison) Failed() bool { return s.plan.failure != "" }
func (s *SemanticCapture) Child(node Snapshot) {
	if node.owner == nil || node.node >= len(node.owner.resources) {
		return
	}
	r := node.owner.resources[node.node]
	s.resources.depth = max(s.resources.depth, s.ownDepth+r.depth)
	s.resources.open = max(s.resources.open, r.open)
	if !s.countsKnown {
		s.resources.elements += r.elements
		s.resources.fragments += r.fragments
	}
}
func (s *SemanticComparison) Child(Snapshot) {}

// ComparisonLimits is a by-value copy of the remaining call ceilings. No
// comparison callback can retain or mutate the encoder's budget through it.
type ComparisonLimits struct {
	Work, Allocated, Elements uint64
	Depth                     int
	limited                   bool
}

func ComparisonBudget(budget *DecodeBudget) ComparisonLimits {
	return ComparisonLimits{Work: uint64(budget.limits.MaxWork) - budget.usage.Work, Allocated: budget.operational.MaxAllocatedBytes - budget.allocated, Elements: uint64(budget.limits.MaxElements) - budget.usage.Elements, Depth: budget.limits.MaxDepth - budget.depth, limited: true}
}
func (s *SemanticComparison) charge(n uint64) {
	if s.plan.failure != "" {
		return
	}
	if s.plan.limits.limited && n > s.plan.limits.Work-s.plan.work {
		s.plan.failure = "comparison work exceeded"
		return
	}
	s.plan.work += n
}
func (p *ReplayPlan) ChargeComparison(budget *DecodeBudget) error {
	bb := NewBudgetBuffer(budget)
	if p.failure != "" {
		return bb.resourceError(p.failure)
	}
	if err := bb.ChargeAllocation(p.allocation, 1); err != nil {
		return err
	}
	return bb.ChargeWork(p.work)
}

// An unchanged comparison has no decisions to publish. The complete encoder
// requests the by-value plan only after discovering an edited occurrence.
func (s *SemanticComparison) Unchanged(root Snapshot) bool {
	return root.owner != nil && !s.changed && !s.Failed() && root == s.plan.root
}
func (s *SemanticComparison) ChargeComparison(budget *DecodeBudget) error {
	return s.plan.ChargeComparison(budget)
}
