// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/inline_bitmap.go; SHA-256 2b8f94cd3d3bf90df60548c53b58679ca5282f6bc2a4b7716e647f4948d0804f.
package uper

import "math"

// EnterInlineBitmapTail scopes whether every enclosing value ends with the
// component being decoded. Generated decoders pass false when any later
// component is mandatory or present, when extension additions follow, or
// when a list element or length fragment is not the last. The returned mark
// must be restored with LeaveInlineBitmapTail.
func (bb *BitBuffer) EnterInlineBitmapTail(final bool) bool {
	if !bb.outermost || bb.trace == nil || bb.trace.inline == nil {
		return false
	}
	previous := bb.trace.inlineBlocked
	bb.trace.inlineBlocked = previous || !final
	return previous
}

// LeaveInlineBitmapTail restores the enclosing component's finality.
func (bb *BitBuffer) LeaveInlineBitmapTail(previous bool) {
	if bb.outermost && bb.trace != nil && bb.trace.inline != nil {
		bb.trace.inlineBlocked = previous
	}
}

// RecoverEmptyInlineBitmap is called only for an inline nonCriticalExtension
// whose resolved type is a non-extensible SEQUENCE with only OPTIONAL root
// components. width is its complete root presence bitmap width. The
// generated caller proves that no later encoded field can follow it by
// scoping every enclosing component with EnterInlineBitmapTail.
//
// X.691 (02/2021) §§19.2–19.4 require the complete bitmap before any
// component, and §11.1.3.1 permits only final zero completion bits. Inferring
// the missing zeros is an explicit receiver choice (go-asn1#207), never a
// standards requirement. The parent's received presence bit proves the child
// present even when every bit of the child's bitmap is absent from the input.
// Open types and contained buffers that arrived in full are ineligible.
//
// On recovery every child remains absent and the returned FinalPadding marks
// that absence as inferred. An unchanged enclosing encoding replays the
// received input through AppendTruncatedExtension. Editing the child or any
// encoded prefix produces a fresh, complete bitmap instead. No encoder runs
// during decode and the default option path allocates nothing.
func (bb *BitBuffer) RecoverEmptyInlineBitmap(width int) (FinalPadding, bool, error) {
	if !bb.outermost || bb.trace == nil || bb.trace.inline == nil || bb.trace.inlineBlocked || bb.invalidLength {
		return FinalPadding{}, false, nil
	}
	// X.691 §19.3 gives maps of 64K or more a fragmented determinant. The
	// generator does not call this helper for that different wire shape.
	if width <= 0 || width >= 64*1024 || bb.bitPos < 0 || bb.bitPos > bb.bitLen || bb.bitLen%8 != 0 || bb.bitLen/8 != len(bb.data) {
		return FinalPadding{}, false, nil
	}
	start, received := bb.bitPos, bb.BitsRemaining()
	if received < 0 || received >= width || width > math.MaxInt-start {
		return FinalPadding{}, false, nil
	}
	// A recovered child still consumes the nesting level its ordinary
	// generated decoder would enter. Receiver policy never raises a limit.
	if err := bb.EnterDecodeValue(); err != nil {
		return FinalPadding{}, false, err
	}
	defer bb.LeaveDecodeValue()
	var bits []byte
	if received > 0 {
		var err error
		bits, err = bb.ReadBitsToBytes(received)
		if err != nil {
			return FinalPadding{}, false, err
		}
	}
	for _, octet := range bits {
		if octet != 0 {
			// The complete bitmap is unavailable regardless of the nonzero
			// bit's meaning, so decoding cannot reach a component value.
			return FinalPadding{}, false, ErrTruncated
		}
	}
	expectedBits := start + width // The guard above proves host-int fit.
	expectedOctets, err := octetsForBitLength(expectedBits)
	if err != nil {
		return FinalPadding{}, false, err
	}
	input := append([]byte(nil), bb.data...)
	expected := make([]byte, expectedOctets)
	copy(expected, input)
	cut := &truncatedExtension{
		input: input, bits: bb.bitLen,
		expected: expected, expectedBits: expectedBits,
		kept: true, cut: true, inline: true,
	}
	bb.trace.pending = append(bb.trace.pending, Tolerance{
		Path: bb.trace.relativePath(), Kind: ToleratedIncompleteInlineBitmap,
		Offset: bb.bitLen, Bits: TrailingBits{Bytes: bits, BitLength: received},
		Missing: width - received,
	})
	return FinalPadding{bits: &finalBits{truncated: cut}}, true, nil
}

// InferredInlineBitmap reports whether this value's all-absent OPTIONAL
// bitmap was inferred from a truncated inline nonCriticalExtension encoding.
// Its components are absent in the decoded value; this record distinguishes
// them from an all-zero bitmap that arrived in full.
func (f FinalPadding) InferredInlineBitmap() bool {
	return f.bits != nil && f.bits.truncated != nil && f.bits.truncated.inline
}

// EnterInlineBitmapElement scopes the last element of a collection fragment.
// The enclosing fragment scope separately requires the final determinant
// (X.691 (02/2021) §11.9.3.8.3). Invalid or nonfinal indices block recovery.
func (bb *BitBuffer) EnterInlineBitmapElement(index, count int64) bool {
	if count <= 0 {
		return bb.EnterInlineBitmapTail(false)
	}
	return bb.EnterInlineBitmapTail(index == count-1)
}
