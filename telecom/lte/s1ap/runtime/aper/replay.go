// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/replay.go; SHA-256 dacef469b92a821be334d91b58c11f779c7d4af0d18ee0473712582ac7d21b50.
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
	data           []byte
	nodes          int
	original       []byte
	budget         DecodeBudget
	report         DecodeReport
	observations   [2]Observation
	reportSpans    [4]BitSpan
	nextReportSpan int
	origin         originMap
	buffers        []BitBuffer
	nextBuffer     int
	scalars        []int64
	nextScalar     int
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

// NewSemanticCapture creates an empty capture with at least 256 bytes of initial
// semantic storage; hint requests a larger initial capacity.
func NewSemanticCapture(hint int) SemanticCapture {
	if hint < 256 {
		hint = 256
	}
	return SemanticCapture{owner: &semanticArena{data: make([]byte, 0, hint), budget: DecodeBudget{limits: defaultLegacyLimits()}}}
}

// Begin starts a nested semantic frame and returns the state needed by End.
func (s *SemanticCapture) Begin() SemanticFrame {
	if s.Err() != nil {
		return SemanticFrame{}
	}
	if !s.reserve(8) {
		return SemanticFrame{}
	}
	f := SemanticFrame{start: len(s.owner.data)}
	s.owner.data = append(s.owner.data, make([]byte, 8)...)
	return f
}

// End finishes the frame begun by Begin and, when node is non-nil, stores its
// snapshot there. The final boolean argument is ignored during capture.
func (s *SemanticCapture) End(f SemanticFrame, node *Snapshot, _ bool) {
	if s.Err() != nil {
		return
	}
	binary.LittleEndian.PutUint64(s.owner.data[f.start:f.start+8], uint64(len(s.owner.data)-f.start-8))
	if node != nil {
		*node = Snapshot{owner: s.owner, start: f.start, end: len(s.owner.data), node: s.owner.nodes}
		s.owner.nodes++
	}
}
func (s *SemanticCapture) fixed(data []byte) {
	if !s.reserve(len(data)) {
		return
	}
	s.owner.data = append(s.owner.data, data...)
}

// Uint records value as an unsigned 64-bit semantic value.
func (s *SemanticCapture) Uint(value uint64) {
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], value)
	s.fixed(data[:])
}

// Int preserves the complete signed value as its unique 64-bit representation.
func (s *SemanticCapture) Int(value int64) { s.Uint(uint64(value)) }

// Bool records value as a one-byte semantic value.
func (s *SemanticCapture) Bool(value bool) {
	var data [1]byte
	if value {
		data[0] = 1
	}
	s.fixed(data[:])
}

// Bytes records the length and an independent copy of value.
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

// BitString records bitLength and, for valid storage, the significant bits of
// value, excluding unused trailing bits and backing bytes
// (X.691 (02/2021) §§16.4–16.5).
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

// String records the byte length and contents of value.
func (s *SemanticCapture) String(value string) {
	s.Uint(uint64(len(value)))
	if !s.reserve(len(value)) {
		return
	}
	s.owner.data = append(s.owner.data, value...)
}

// BigInt records nil distinctly from zero, then the sign and magnitude words
// of a non-nil value.
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

// Opaque records the effective contents of value, using its received wire
// image when present and its stored bytes otherwise.
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

// ChoiceExtension records whether value is nil and, when present, its
// extension index and effective open-type contents.
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
		p.extra = make([]uint8, (p.root.owner.nodes-1)/8+1-len(p.states))
	}
	p.extra[index-len(p.states)] |= mask
}

// Unchanged reports whether node belongs to the plan and has no recorded
// change. A nil or zero plan, or a zero snapshot, returns false.
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

// Present reports whether the snapshot has an owner; a zero snapshot returns false.
func (s Snapshot) Present() bool { return s.owner != nil }

// SemanticComparison reads the baseline and settles each occurrence in one
// postorder traversal, independently of the write-capable capture API. Its
// saved scan is charged once before traversal; contents beyond that baseline
// are charged before examination. No semantic field or PER encoder is skipped.
type SemanticComparison struct {
	plan       ReplayPlan
	pos, limit int
	valueDepth int
	changed    bool
	budget     DecodeBudget
	hasBudget  bool
}

// NewSemanticComparison starts a comparison at root. When a budget is supplied,
// it copies the first budget and charges the saved baseline scan before traversal;
// without a budget, comparison resource accounting is disabled.
func NewSemanticComparison(root Snapshot, budgets ...DecodeBudget) SemanticComparison {
	s := SemanticComparison{plan: ReplayPlan{root: root}, pos: root.start, limit: root.end}

	if len(budgets) > 0 {
		s.budget = budgets[0]
		s.hasBudget = true
		s.valueDepth = s.budget.depth
		_ = s.budget.chargeWork(uint64(root.end - root.start))
	}
	return s
}

// Plan returns the comparison decisions accumulated so far. A zero comparison
// returns a zero plan.
func (s *SemanticComparison) Plan() ReplayPlan { return s.plan }

// Begin starts comparison of a nested semantic frame and returns the state
// needed by End.
func (s *SemanticComparison) Begin() SemanticFrame {
	if s.Err() != nil {
		return SemanticFrame{}
	}
	if s.hasBudget {
		if s.valueDepth >= s.budget.limits.MaxDepth {
			_ = NewBudgetBuffer(&s.budget).resourceError("PER nesting depth exceeded")
			return SemanticFrame{}
		}
		s.valueDepth++
		if s.valueDepth > s.budget.usage.MaxDepth {
			s.budget.usage.MaxDepth = s.valueDepth
		}
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
		if !s.work(8) {
			return SemanticFrame{}
		}
		s.changed = true
	}
	s.limit = f.end
	return f
}

// End finishes the frame begun by Begin, marks node changed when its semantics
// or frame bounds differ or fresh is true, and restores the enclosing frame.
func (s *SemanticComparison) End(f SemanticFrame, node Snapshot, fresh bool) {
	if s.Err() != nil {
		return
	}
	if s.hasBudget && s.valueDepth > s.budget.depth {
		s.valueDepth--
	}
	if s.pos != f.end || fresh {
		s.changed = true
	}
	if node.owner != nil && node.owner == s.plan.root.owner {
		dirty := s.changed || node.start != f.start || node.end != f.end
		if dirty {
			if s.hasBudget && s.plan.extra == nil && node.node/8 >= len(s.plan.states) {
				if ChargeSlice[uint8](NewBudgetBuffer(&s.budget), uint64((s.plan.root.owner.nodes-1)/8+1-len(s.plan.states))) != nil {
					return
				}
			}
			s.plan.markChanged(node.node)
		}
	}
	s.changed = s.changed || f.changed
	s.pos, s.limit = f.end, f.limit
}
func (s *SemanticComparison) fixed(data []byte) {
	if len(data) > s.limit-s.pos {
		if !s.work(uint64(len(data) - (s.limit - s.pos))) {
			return
		}
		s.changed = true
		s.pos = s.limit
		return
	}
	if !bytes.Equal(data, s.plan.root.owner.data[s.pos:s.pos+len(data)]) {
		s.changed = true
	}
	s.pos += len(data)
}

// Uint compares value with the next unsigned 64-bit baseline value.
func (s *SemanticComparison) Uint(value uint64) {
	if s.pos > s.limit-8 {
		if !s.work(8) {
			return
		}
		s.changed = true
		s.pos = s.limit
		return
	}
	if binary.LittleEndian.Uint64(s.plan.root.owner.data[s.pos:s.pos+8]) != value {
		s.changed = true
	}
	s.pos += 8
}

// Int compares the complete signed value with the next 64-bit baseline value.
func (s *SemanticComparison) Int(value int64) { s.Uint(uint64(value)) }

// Bool compares value with the next one-byte baseline boolean.
func (s *SemanticComparison) Bool(value bool) {
	var data [1]byte
	if value {
		data[0] = 1
	}
	s.fixed(data[:])
}
func (s *SemanticComparison) length() int {
	if s.pos > s.limit-8 {
		if !s.work(8) {
			return -1
		}
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

// Bytes compares the length and contents of value with the next baseline byte slice.
func (s *SemanticComparison) Bytes(value []byte) {
	n := s.length()
	if len(value) > max(n, 0) && !s.work(uint64(len(value)-max(n, 0))) {
		return
	}
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

// BitString compares bitLength and, for valid storage, the significant bits of
// value with the baseline, excluding unused trailing bits and backing bytes
// (X.691 (02/2021) §§16.4–16.5).
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

// String compares the byte contents of value with the next baseline string.
func (s *SemanticComparison) String(value string) {
	n := s.length()
	if len(value) > max(n, 0) && !s.work(uint64(len(value)-max(n, 0))) {
		return
	}
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

// BigInt compares nil presence and, for non-nil values, sign and magnitude
// words with the baseline.
func (s *SemanticComparison) BigInt(value *big.Int) {
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

// Opaque compares the effective contents of value with the baseline, using
// its received wire image when present and its stored bytes otherwise. It
// charges open-type framing when comparison resource accounting is enabled.
func (s *SemanticComparison) Opaque(value OpaqueOpenType) {
	if s.hasBudget {
		length := len(value.bytes)
		if value.image.Present() {
			length = value.image.Len()
		}
		if NewBudgetBuffer(&s.budget).ChargeOpenTypeFraming(uint64(length)) != nil {
			return
		}
	}
	if !value.image.Present() {
		s.Bytes(value.bytes)
		return
	}
	n := s.length()
	if value.image.Len() > max(n, 0) && !s.work(uint64(value.image.Len()-max(n, 0))) {
		return
	}
	if n != value.image.Len() {
		s.changed = true
		if n >= 0 && n <= s.limit-s.pos {
			s.pos += n
		} else {
			s.pos = s.limit
		}
		return
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

// ChoiceExtension compares nil presence and, for non-nil values, the extension
// index and effective open-type contents with the baseline.
func (s *SemanticComparison) ChoiceExtension(value *ChoiceExtension) {
	s.Bool(value == nil)
	if value != nil {
		s.Uint(uint64(value.index))
		s.Opaque(OpaqueOpenType{bytes: value.contents, image: value.image})
	}
}

// NewEncodeBuffer creates an empty encoder buffer with plan attached. A nil
// plan returns a zero buffer.
func NewEncodeBuffer(plan *ReplayPlan) *BitBuffer {
	if plan == nil {
		return &BitBuffer{}
	}
	return &BitBuffer{budget: &DecodeBudget{encodePlan: plan}}
}

// ReplayPlan returns the attached encoder comparison plan, or nil when none
// is attached. A zero buffer returns nil.
func (bb *BitBuffer) ReplayPlan() *ReplayPlan {
	if bb.budget == nil {
		return nil
	}
	return bb.budget.encodePlan
}

// FirstReplayPlan returns the first supplied plan, including nil, or nil when
// no plans are supplied.
func FirstReplayPlan(plans ...*ReplayPlan) *ReplayPlan {
	if len(plans) > 0 {
		return plans[0]
	}
	return nil
}

// newSemanticOwner packs the original, small snapshots, scalar arms and decoder
// state into a single lifetime. Larger content grows only the corresponding
// bounded backing slice, never an enclosing wire copy.
type smallDecodeOwner struct {
	arena     semanticArena
	original  [8]byte
	semantics [128]byte
	buffers   [1]BitBuffer
	scalars   [1]int64
}
type messageDecodeOwner struct {
	arena     semanticArena
	original  [64]byte
	semantics [512]byte
	buffers   [8]BitBuffer
	scalars   [8]int64
}

func newSemanticOwner(data []byte) *semanticArena {
	var owner *semanticArena
	if len(data) <= 8 {
		p := new(smallDecodeOwner)
		owner = &p.arena
		owner.original = append(p.original[:0], data...)
		owner.data = p.semantics[:0]
		owner.buffers = p.buffers[:]
		owner.scalars = p.scalars[:]
	} else {
		p := new(messageDecodeOwner)
		owner = &p.arena
		owner.original = append(p.original[:0], data...)
		owner.data = p.semantics[:0]
		owner.buffers = p.buffers[:]
		owner.scalars = p.scalars[:]
	}
	owner.budget.limits = defaultLegacyLimits()
	owner.budget.owner = owner
	owner.budget.origin = &owner.origin
	return owner
}

// NewCompleteDecodeBuffer creates a reader for data using the decode state
// owner when available. A zero decode state creates an ordinary byte reader.
func NewCompleteDecodeBuffer(data []byte, state DecodeState) *BitBuffer {
	if state.settings.owner == nil {
		return NewBitBufferFromBytes(data)
	}
	return state.settings.owner.buffer(data, nil)
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
		if NewBudgetBuffer(&o.budget).ChargeAllocation(1, 64) != nil {
			return &BitBuffer{budget: &o.budget}
		}
		bb = new(BitBuffer)
	}
	*bb = BitBuffer{sourceReader: true, data: data, budget: &o.budget}
	if len(data) > int(^uint(0)>>1)/8 {
		bb.invalidLength = true
	} else {
		bb.bitLen = len(data) * 8
	}
	if parent != nil {
		bb.nested = true
		bb.trace = parent.trace
		bb.zeroWidthLimit = parent.zeroWidthLimit
	}
	return bb
}

// SemanticCaptureFor returns a capture using the decode state owner when
// available. A zero decode state creates a new capture with 256 bytes of
// initial semantic storage.
func SemanticCaptureFor(state DecodeState) SemanticCapture {
	if state.settings.owner == nil {
		return NewSemanticCapture(256)
	}
	return SemanticCapture{owner: state.settings.owner}
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
	if bb.ChargeAllocation(1, 8) != nil {
		return nil
	}
	p := new(int64)
	*p = value
	return p
}

// ExtensionData observes effective unknown contents independently of whether
// they came from a caller's mutable setter or an immutable received span.
func (s *SemanticCapture) ExtensionData(data [][]byte, spans []WireSpan, known ...int) {
	f := s.Begin()
	n := max(len(data), len(spans))
	first := 0
	if len(known) > 0 {
		first = known[0]
	}
	for i := first; i < n; i++ {
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

// ExtensionData compares effective unknown extension contents with the baseline,
// preferring a non-nil data entry to the corresponding received span. The first
// optional known index selects the first extension examined; it defaults to zero.
func (s *SemanticComparison) ExtensionData(data [][]byte, spans []WireSpan, known ...int) {
	f := s.Begin()
	n := max(len(data), len(spans))
	first := 0
	if len(known) > 0 {
		first = known[0]
	}
	for i := first; i < n; i++ {
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

// RestoreReplayPlan restores the encoder plan when the buffer has a budget.
// It has no effect on a zero buffer.
func (bb *BitBuffer) RestoreReplayPlan(previous *ReplayPlan) {
	if bb.budget != nil {
		bb.budget.encodePlan = previous
	}
}

// SetReplayPlan attaches decisions to one encoder operation.
func (b *DecodeBudget) SetReplayPlan(plan *ReplayPlan) { b.encodePlan = plan }

// Err is the latched per-operation failure; visitors stop before more traversal.
func (s *SemanticCapture) Err() error {
	if s.owner == nil {
		return ErrInvalidValue
	}
	return s.owner.budget.err
}
func (s *SemanticCapture) reserve(n int) bool {
	if s.owner.budget.chargeWork(uint64(n)) != nil {
		return false
	}
	bb := NewBudgetBuffer(&s.owner.budget)
	if n > int(^uint(0)>>1)-len(s.owner.data) {
		_ = bb.resourceError("snapshot size overflows")
		return false
	}
	needed := len(s.owner.data) + n
	if needed > cap(s.owner.data) {
		capacity := needed
		if cap(s.owner.data) <= int(^uint(0)>>1)/2 {
			capacity = max(capacity, cap(s.owner.data)*2)
		}
		if bb.ChargeAllocation(uint64(capacity), 1) != nil {
			return false
		}
		next := make([]byte, len(s.owner.data), capacity)
		copy(next, s.owner.data)
		s.owner.data = next
	}
	return true
}

// Err returns the latched comparison budget error, or nil when no budget was
// supplied. A zero comparison returns nil.
func (s *SemanticComparison) Err() error {
	if !s.hasBudget {
		return nil
	}
	return s.budget.err
}
func (s *SemanticComparison) work(n uint64) bool {
	return !s.hasBudget || s.budget.chargeWork(n) == nil
}

// Elements charges n units of capture work unless the capture has already failed.
func (s *SemanticCapture) Elements(n int) {
	if s.Err() == nil {
		_ = s.owner.budget.chargeWork(uint64(n))
	}
}

// Elements charges n elements when comparison resource accounting is enabled.
func (s *SemanticComparison) Elements(n int) {
	if s.hasBudget {
		_ = NewBudgetBuffer(&s.budget).ChargeElements(int64(n))
	}
}

// OpenType charges framing for a present received open type when comparison
// resource accounting is enabled.
func (s *SemanticComparison) OpenType(wire WireSpan) {
	if s.hasBudget && wire.Present() {
		_ = NewBudgetBuffer(&s.budget).ChargeOpenTypeFraming(uint64(wire.Len()))
	}
}

// CheckReceived has no effect during capture; received replay framing is
// checked during comparison.
func (s *SemanticCapture) CheckReceived(_ Snapshot, _ WireSpan) {}

// CheckReceived charges open-type framing for a present wire when node is unchanged and comparison resource accounting is enabled.
func (s *SemanticComparison) CheckReceived(node Snapshot, wire WireSpan) {
	if s.plan.Unchanged(node) {
		s.OpenType(wire)
	}
}

// CheckChoice has no effect during capture; choice replay framing is checked
// during comparison.
func (s *SemanticCapture) CheckChoice(_ Snapshot, _ WireSpan) {}

// CheckChoice charges received choice replay framing when node is unchanged,
// wire is present, and comparison resource accounting is enabled.
func (s *SemanticComparison) CheckChoice(node Snapshot, wire WireSpan) {
	if s.hasBudget && s.plan.Unchanged(node) && wire.Present() {
		_ = chargeChoiceReplay(wire, &s.budget)
	}
}

// BudgetValue returns the counters settled with this comparison.
func (s *SemanticComparison) BudgetValue() DecodeBudget {
	_ = s.Err()
	s.budget.publish()
	return s.budget
}

// ownedMetadataBytes includes the fixed semantic, scalar, cursor and report slots.
func ownedMetadataBytes(size int) uint64 {
	if size <= 8 {
		return max(operationMetadataBytes, uint64(unsafe.Sizeof(smallDecodeOwner{})))
	}
	return max(operationMetadataBytes, uint64(unsafe.Sizeof(messageDecodeOwner{})))
}
