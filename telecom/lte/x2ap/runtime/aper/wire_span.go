// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/wire_span.go; SHA-256 cf615f9e57e6f80f8c62ff548bba8247647346d4b3028049a1c5a487e01d03d0.
package aper

import "math"

// WireSpan retains source-relative bits in one immutable original owner.
// X.691 (02/2021) §§11.1–11.2 determine alignment; §11.9.3.8 permits
// interleaved fragment determinants, which are excluded from content spans.
type WireSpan struct {
	original   []byte
	start, end uint64
	segments   []BitSpan
}

// OriginalWire names complete octets already owned by the complete decoder.
// Generated code calls this only after OwnDecodeInput establishes ownership.
func OriginalWire(original []byte) WireSpan {
	if len(original) > math.MaxInt/8 {
		return WireSpan{}
	}
	return WireSpan{original: original, end: uint64(len(original)) * 8}
}

// Present reports whether the span retains an original buffer; the zero value returns false.
func (s WireSpan) Present() bool { return s.original != nil }
func (s WireSpan) bitLength() uint64 {
	if len(s.segments) == 0 {
		return s.end - s.start
	}
	var n uint64
	for _, p := range s.segments {
		n += p.End - p.Start
	}
	return n
}

// Len returns the number of octets needed for the span's bits, rounded up.
// The zero value returns zero.
func (s WireSpan) Len() int { return int((s.bitLength() + 7) / 8) }

// Bytes copies complete received octets on demand, including fragmented forms.
// It never invokes a value encoder and never joins content during decoding.
func (s WireSpan) Bytes() []byte {
	if !s.Present() {
		return nil
	}
	out := make([]byte, s.Len())
	if len(s.segments) == 0 && s.start%8 == 0 && s.end%8 == 0 {
		copy(out, s.original[s.start/8:s.end/8])
		return out
	}
	writer := BitBuffer{data: out[:0]}
	_, err := s.copyTo(&writer, false)
	if err != nil {
		return nil
	}
	return writer.data
}

// CaptureWireSpan retains the bits from start to the current cursor without
// copying contents. It returns an absent span if the buffer does not own its
// input, start is invalid, or the original-input mapping is unavailable.
func (bb *BitBuffer) CaptureWireSpan(start int) WireSpan {
	if !bb.ownsInput() || start < 0 || start > bb.bitPos {
		return WireSpan{}
	}
	original := bb.decodeBudget().owner.original
	if span, ok := originalContiguousRange(bb, uint64(start), uint64(bb.bitPos)); ok {
		return WireSpan{original: original, start: span.Start, end: span.End}
	}
	spans, ok := originalRange(bb, uint64(start), uint64(bb.bitPos))
	if !ok {
		return WireSpan{}
	}
	if len(spans) == 1 {
		return WireSpan{original: original, start: spans[0].Start, end: spans[0].End}
	}
	return WireSpan{original: original, segments: spans}
}

// ReplayTo uses received bits only when their original local alignment still
// matches. Each span's aligned middle is copied; at most fourteen edge bits
// per physical fragment use WriteBit. The fragment gaps are never replayed.
func (s WireSpan) ReplayTo(bb *BitBuffer) (bool, error) { return s.copyTo(bb, true) }
func (s WireSpan) copyTo(bb *BitBuffer, qualified bool) (bool, error) {
	if !s.Present() {
		return false, nil
	}
	first := s.start
	if len(s.segments) > 0 {
		first = s.segments[0].Start
	}
	if qualified && first%8 != uint64(bb.bitPos%8) {
		return false, nil
	}
	if len(s.segments) == 0 {
		if err := s.copySpan(bb, BitSpan{Start: s.start, End: s.end}); err != nil {
			return false, err
		}
		return true, nil
	}
	for _, p := range s.segments {
		if err := s.copySpan(bb, p); err != nil {
			return false, err
		}
	}
	return true, nil
}
func (s WireSpan) copySpan(bb *BitBuffer, p BitSpan) error {
	if p.End < p.Start || p.End > uint64(len(s.original))*8 {
		return ErrInvalidValue
	}
	start, end := p.Start, p.End
	for start < end && (start%8 != 0 || bb.bitPos%8 != 0) {
		if err := bb.WriteBit(s.original[start/8] >> (7 - start%8) & 1); err != nil {
			return err
		}
		start++
	}
	wholeEnd := end / 8 * 8
	if wholeEnd > start {
		if err := bb.WriteBytes(s.original[start/8 : wholeEnd/8]); err != nil {
			return err
		}
		start = wholeEnd
	}
	for start < end {
		if err := bb.WriteBit(s.original[start/8] >> (7 - start%8) & 1); err != nil {
			return err
		}
		start++
	}
	return nil
}

// ContentLocation returns fresh span storage; the original owner's metadata
// remains immutable even if a caller changes the returned diagnostic.
func (s WireSpan) ContentLocation() Location {
	if !s.Present() {
		return Location{}
	}
	spans := s.segments
	if len(spans) == 0 {
		spans = []BitSpan{{Start: s.start, End: s.end}}
	}
	return Location{Spans: append([]BitSpan(nil), spans...), HasWireLocation: true}
}

// EncodeBytes copies a complete received value under this encode's ceilings.
func (s WireSpan) EncodeBytes(budget *DecodeBudget) ([]byte, error) {
	bb := NewBudgetBuffer(budget)
	if err := bb.CheckOutput(uint64(s.Len())); err != nil {
		return nil, err
	}
	if err := bb.ChargeAllocation(uint64(s.Len()), 1); err != nil {
		return nil, err
	}
	return s.Bytes(), nil
}

// EncodePlanBytes keeps an unchanged encode's counters on this call's stack.
func (s WireSpan) EncodePlanBytes(plan ReplayPlan) ([]byte, error) {
	if plan.budget.err != nil {
		return nil, plan.budget.err
	}
	return s.EncodeBytes(&plan.budget)
}

// encodeOpenTo writes logical open contents directly from immutable original
// spans. X.691 (02/2021) §§11.2.1–11.2.2 and 11.9.3.8 determine framing.
func (s WireSpan) encodeOpenTo(bb *BitBuffer) error {
	if !s.Present() || s.bitLength()%8 != 0 || s.Len() == 0 {
		return ErrInvalidValue
	}
	if uint64(s.Len()) > bb.openTypeMaximum() {
		return bb.resourceError("open type bytes exceeded")
	}
	if err := bb.EnterOpenType(); err != nil {
		return err
	}
	defer bb.LeaveOpenType()
	return EncodeLengthFragments(bb, int64(s.Len()), true, func(offset, length int64) error { return s.copyOctetRangeTo(bb, offset, length) })
}
func (s WireSpan) copyOctetRangeTo(bb *BitBuffer, offset, length int64) error {
	if offset < 0 || length < 0 || offset > int64(s.Len()) || length > int64(s.Len())-offset {
		return ErrInvalidValue
	}
	skip, remaining := uint64(offset)*8, uint64(length)*8
	parts := s.segments
	var one [1]BitSpan
	if len(parts) == 0 {
		one[0] = BitSpan{Start: s.start, End: s.end}
		parts = one[:]
	}
	for _, part := range parts {
		if part.End < part.Start || part.End > uint64(len(s.original))*8 {
			return ErrInvalidValue
		}
		width := part.End - part.Start
		if skip >= width {
			skip -= width
			continue
		}
		count := min(remaining, width-skip)
		if err := s.copySpan(bb, BitSpan{Start: part.Start + skip, End: part.Start + skip + count}); err != nil {
			return err
		}
		remaining -= count
		skip = 0
		if remaining == 0 {
			return nil
		}
	}
	if remaining != 0 {
		return ErrInvalidValue
	}
	return nil
}
