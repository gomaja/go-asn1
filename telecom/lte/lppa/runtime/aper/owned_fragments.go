// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/owned_fragments.go; SHA-256 e61b91d8a947160ef1e8e5f2a5eac5b8ca8a730a7675cd613bb148e8dfc2cc6b.
package aper

import (
	"math"
	"sort"
)

// fragmentedReader maps logical content octets directly to their physical
// original spans. The cursor makes sequential reads linear in content and
// fragments. Random recovery reads use the sorted source map.
type fragmentedReader struct {
	segments []wireSegment
	original []byte
	cursor   int
}

func (r *fragmentedReader) octet(index int) byte {
	bit := uint64(index) * 8
	i := r.cursor
	if i >= len(r.segments) || bit < r.segments[i].localStart {
		i = sort.Search(len(r.segments), func(i int) bool { return r.segments[i].localEnd > bit })
	} else {
		for i < len(r.segments) && bit >= r.segments[i].localEnd {
			i++
		}
	}
	r.cursor = i
	p := r.segments[i]
	return r.original[(p.sourceStart+bit-p.localStart)/8]
}
func (bb *BitBuffer) fragmented() bool { return bb.bitLen > len(bb.data)*8 && !bb.invalidLength }
func (bb *BitBuffer) readOctet(index int) byte {
	if !bb.fragmented() {
		return bb.data[index]
	}
	return bb.budget.origin.readers[bb].octet(index)
}
func (bb *BitBuffer) copyOctets(dst []byte, start int) {
	if !bb.fragmented() {
		copy(dst, bb.data[start:start+len(dst)])
		return
	}
	for i := range dst {
		dst[i] = bb.readOctet(start + i)
	}
}
func (s WireSpan) decodeBuffer(parent *BitBuffer) *BitBuffer {
	data := s.original[s.start/8 : s.end/8]
	if len(s.segments) > 0 {
		first := s.segments[0]
		data = s.original[first.Start/8 : first.End/8]
	}
	var child *BitBuffer
	if parent == nil {
		child = NewBitBufferFromBytes(s.Bytes())
		child.nested = true
	} else {
		child = NewOwnedNestedDecodeBuffer(data, parent)
	}
	if len(s.segments) == 0 {
		if base, ok := child.ownedInputBase(); ok && base == s.start {
			return child
		}
	}
	origin := child.decodeBudget().origin
	if origin == nil {
		if err := ChargeValue(child, originMap{}); err != nil {
			return child
		}
		origin = &originMap{}
		child.budget.origin = origin
	}
	if len(s.segments) == 0 {
		if err := child.recordOriginBase(s.start); err != nil {
			return child
		}
		return child
	}
	if err := ChargeSlice[wireSegment](child, uint64(len(s.segments))); err != nil {
		return child
	}
	segments := make([]wireSegment, len(s.segments))
	var offset uint64
	for i, p := range s.segments {
		n := p.End - p.Start
		segments[i] = wireSegment{localStart: offset, localEnd: offset + n, sourceStart: p.Start}
		offset += n
	}
	child.bitLen = int(offset)
	if origin.segments == nil {
		origin.segments = make(map[*BitBuffer][]wireSegment)
	}
	if err := ReserveMapEntry(child, origin.segments, child); err != nil {
		return child
	}
	origin.segments[child] = segments
	if parent != nil {
		if origin.readers == nil {
			origin.readers = make(map[*BitBuffer]*fragmentedReader)
		}
		if err := ReserveMapEntry(child, origin.readers, child); err != nil {
			return child
		}
		if err := ChargeValue(child, fragmentedReader{}); err != nil {
			return child
		}
		origin.readers[child] = &fragmentedReader{segments: segments, original: s.original}
	}

	return child
}

// decodeOwnedOpaque parses length determinants without joining fragments.
// X.691 (02/2021) §§11.2.2 and 11.9.3.8 delimit their complete contents.
func decodeOwnedOpaque(bb *BitBuffer, reason OpaqueReason, rule SourceRule) (OpaqueOpenType, error) {
	if err := bb.EnterOpenType(); err != nil {
		return OpaqueOpenType{}, err
	}
	defer bb.LeaveOpenType()
	start := bb.BitPos()
	var first BitSpan
	var spans []BitSpan
	count := 0
	total, err := decodeLengthFragmentsBounded(bb, true, math.MaxInt64, func(offset int64, n int64) error {
		if limit := bb.decodeBudget().operational.MaxOpenTypeBytes; limit != 0 && (uint64(offset) > limit || uint64(n) > limit-uint64(offset)) {
			return bb.resourceError("open type bytes exceeded")
		}
		if n < 0 || n > int64(math.MaxInt) || n > int64(bb.BitsRemaining()/8) {
			return ErrTruncated
		}
		bitStart := bb.BitPos()
		if err := bb.examineRecoveryBits(uint64(n) * 8); err != nil {
			return err
		}
		bb.bitPos += int(n) * 8
		if n == 0 {
			return nil
		}
		add := func(p BitSpan) {
			if count == 0 {
				first = p
			} else {
				if count == 1 {
					spans, _ = AppendValues(bb, spans, first)
				}
				spans, _ = AppendValues(bb, spans, p)
			}
			count++
		}
		if p, ok := originalContiguousRange(bb, uint64(bitStart), uint64(bb.BitPos())); ok {
			add(p)
			return nil
		}
		parts, ok := originalRange(bb, uint64(bitStart), uint64(bb.BitPos()))
		if !ok {
			return ErrInvalidValue
		}
		for _, p := range parts {
			add(p)
		}
		return nil
	})
	if err != nil {
		return OpaqueOpenType{}, err
	}
	if bb.budget.err != nil {
		return OpaqueOpenType{}, bb.budget.err
	}
	if total == 0 {
		return OpaqueOpenType{}, ErrInvalidValue
	}
	image := WireSpan{original: bb.budget.owner.original, start: first.Start, end: first.End, segments: spans}
	framing := bb.CaptureWireSpan(start)
	if bb.budget.err != nil {
		return OpaqueOpenType{}, bb.budget.err
	}
	return OpaqueOpenType{image: image, framing: framing, parent: bb, origin: OpaqueOrigin{Reason: reason, Rule: rule, HasWireLocation: true, SourceVersion: rule.Edition}}, nil
}

// A fixed owner-local prefix avoids map allocations for ordinary LPPa messages.
// Beyond it, the ordinary budgeted origin map remains bounded by node count.
func (bb *BitBuffer) recordOriginBase(base uint64) error {
	origin := bb.decodeBudget().origin
	if bb.ownsInput() {
		for i := 0; i < origin.inlineCount; i++ {
			if origin.inline[i].buffer == bb {
				origin.inline[i].base = base
				return nil
			}
		}
		if origin.inlineCount < len(origin.inline) {
			i := origin.inlineCount
			origin.inline[i].buffer = bb
			origin.inline[i].base = base
			origin.inlineCount++
			return nil
		}
	}
	if err := ReserveMapEntry(bb, origin.bases, bb); err != nil {
		return err
	}
	if origin.bases == nil {
		origin.bases = make(map[*BitBuffer]uint64)
	}
	origin.bases[bb] = base
	return nil
}
func (o *originMap) lookupBase(bb *BitBuffer) (uint64, bool) {
	for i := 0; i < o.inlineCount; i++ {
		if o.inline[i].buffer == bb {
			return o.inline[i].base, true
		}
	}
	base, ok := o.bases[bb]
	return base, ok
}
func (o *originMap) clearInlineBase(bb *BitBuffer) {
	for i := 0; i < o.inlineCount; i++ {
		if o.inline[i].buffer == bb {
			o.inline[i].buffer = nil
		}
	}
}
