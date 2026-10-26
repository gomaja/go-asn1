// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/owned_fragments.go; SHA-256 88f4f832a63c0a17aede8e73f230db5478f5297b2c2c6b91860dee61f60efa32.
package aper

import (
	"errors"
	"fmt"
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
	origin := child.decodeBudget().origin
	if origin == nil {
		if err := ChargeValue(child, originMap{}); err != nil {
			return child
		}
		origin = &originMap{}
		child.budget.origin = origin
	}
	if len(s.segments) == 0 {
		if err := ReserveMapEntry(child, origin.bases, child); err != nil {
			return child
		}
		if origin.bases == nil {
			origin.bases = make(map[*BitBuffer]uint64)
		}
		origin.bases[child] = s.start
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
	if offset > uint64(math.MaxInt) {
		child.decodeBudget().err = ErrInvalidValue
		return child
	}
	child.bitLen = int(offset)
	if err := ReserveMapEntry(child, origin.segments, child); err != nil {
		return child
	}
	if origin.segments == nil {
		origin.segments = make(map[*BitBuffer][]wireSegment)
	}
	origin.segments[child] = segments
	if parent != nil {
		if err := ReserveMapEntry(child, origin.readers, child); err != nil {
			return child
		}
		if err := ChargeValue(child, fragmentedReader{}); err != nil {
			return child
		}
		if origin.readers == nil {
			origin.readers = make(map[*BitBuffer]*fragmentedReader)
		}
		origin.readers[child] = &fragmentedReader{segments: segments, original: s.original}
	}
	return child
}

// decodeOwnedOpaque parses length determinants without joining fragments.
// X.691 (02/2021) §§11.2.2 and 11.9.3.8 delimit their complete contents.
func decodeOwnedOpaque(bb *BitBuffer, reason OpaqueReason, rule SourceRule) (result OpaqueOpenType, resultErr error) {
	sourceStart := bb.BitPos()
	defer bb.locateDecodeFailure(sourceStart, "§11.2.1", &resultErr)
	if err := bb.EnterOpenType(); err != nil {
		return OpaqueOpenType{}, err
	}
	defer bb.LeaveOpenType()
	start := bb.BitPos()
	var first BitSpan
	var spans []BitSpan
	count := 0
	total, err := decodeLengthFragmentsBounded(bb, true, int64(bb.openTypeMaximum()), func(offset int64, n int64) error {
		if n < 0 || n > int64(math.MaxInt) {
			return fmt.Errorf("%w: fragment length %d exceeds host int", ErrInvalidValue, n)
		}
		if n > int64(bb.BitsRemaining()/8) {
			if offset > 0 || n >= perFragmentUnit {
				return bb.syntaxError(bb.BitPos(), "§11.9.3.8.2", "incomplete fragment contents", ErrTruncated)
			}
			return fmt.Errorf("%w: fragment requires %d octets with %d bits remaining", ErrTruncated, n, bb.BitsRemaining())
		}
		bitStart := bb.BitPos()
		if err := bb.examineReadBits(uint64(n) * 8); err != nil {
			return err
		}
		bb.bitPos += int(n) * 8
		if n == 0 {
			return nil
		}
		add := func(p BitSpan) error {
			if count == 0 {
				first = p
			} else {
				var err error
				if count == 1 {
					spans, err = AppendValues(bb, spans, first, p)
				} else {
					spans, err = AppendValues(bb, spans, p)
				}
				if err != nil {
					return err
				}
			}
			count++
			return nil
		}
		if p, ok := originalContiguousRange(bb, uint64(bitStart), uint64(bb.BitPos())); ok {
			return add(p)
		}
		parts, ok := originalRange(bb, uint64(bitStart), uint64(bb.BitPos()))
		if !ok {
			return ErrInvalidValue
		}
		for _, p := range parts {
			if err := add(p); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrConstraintViolation) && bb.decodeBudget().operational.MaxOpenTypeBytes != 0 {
			return OpaqueOpenType{}, bb.resourceError("open type bytes exceeded")
		}
		return OpaqueOpenType{}, err
	}
	if total == 0 {
		return OpaqueOpenType{}, bb.syntaxError(bb.BitPos(), "§11.2.1", "APER open type has an empty complete encoding", ErrInvalidValue)
	}
	image := WireSpan{original: bb.budget.owner.original, start: first.Start, end: first.End, segments: spans}
	location := bb.captureSpanLocation(bb.CaptureWireSpan(start))
	return OpaqueOpenType{image: image, parent: bb, origin: OpaqueOrigin{Reason: reason, Rule: rule, Location: location, HasWireLocation: location.HasWireLocation, SourceVersion: rule.Edition}}, nil
}
