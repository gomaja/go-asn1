// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/tolerance.go; SHA-256 35d8cf6dafb8feb2e9c9535d3b3e63f8dbfdc2d811de893466c2fe79d643d8ec.
package aper

import "strings"

// decodeTrace is shared by readers only for explicit terminal-padding observations.
type decodeTrace struct {
	terminalPadding bool
	nonzeroPadding  bool
	path            []pathSegment
}

// pathSegment is a component name, or a list index when name is empty.
type pathSegment struct {
	name  string
	index int64
}

// EnterComponent marks the start of a component decode that can apply a
// tolerance. Pass the returned mark to LeaveComponent.
func (bb *BitBuffer) EnterComponent(name string) int {
	if bb.trace == nil {
		return 0
	}
	return bb.enterPaddingSegment(pathSegment{name: name})
}

// EnterIndex marks the start of a list element decode that can apply a
// tolerance. Pass the returned mark to LeaveComponent.
func (bb *BitBuffer) EnterIndex(index int64) int {
	if bb.trace == nil {
		return 0
	}
	return bb.enterPaddingSegment(pathSegment{index: index})
}

// LeaveComponent restores the path recorded before the matching Enter call.
func (bb *BitBuffer) LeaveComponent(mark int) {
	if bb.trace != nil && mark >= 0 && mark <= len(bb.trace.path) {
		bb.trace.path = bb.trace.path[:mark]
	}
}

// qualifyPath prefixes a path relative to the top-level value with root, in
// the form of runtime.DecodePathError.
func qualifyPath(root, path string) string {
	switch {
	case path == "":
		return root
	case strings.HasPrefix(path, "["):
		return strings.Join([]string{root, path}, "")
	default:
		return strings.Join([]string{root, path}, ".")
	}
}

// CaptureFinalBits validates terminal padding, or records a departure under
// WithNonzeroTerminalPadding, returning zero padding state. It publishes records with the
// top-level path (X.691 (02/2021) §11.1.4).
func CaptureFinalBits(bb *BitBuffer, root string) (FinalPadding, error) {
	if err := bb.checkReadBits(0); err != nil {
		return FinalPadding{}, err
	}
	padding, err := captureNamedPadding(bb, "top-level value", root)
	if err != nil {
		return FinalPadding{}, err
	}
	final := finalPaddingOf(padding)
	if bb.trace != nil && bb.trace.terminalPadding {
		if err := bb.qualifyPaddingReports(root); err != nil {
			return FinalPadding{}, err
		}
	}
	return final, nil
}

// FinalPadding carries complete-value padding state.
// Successful APER decoding leaves the padding state zero (X.691 (02/2021)
// §11.1.4). Only package-internal callers can supply non-zero padding state;
// its stored bits are replayed while they still fill the final octet exactly.
type FinalPadding struct{ bits *finalBits }

type finalBits struct {
	padding CompletePadding
}

// paddingTable holds every CompletePadding with one to seven bits. The entry
// for count bits with value v is at paddingTableOffset[count] + v, and
// paddingTableOffset[count] = 2^count - 1 is also the largest such v.
var paddingTable = func() (table [255]finalBits) {
	for count := uint8(1); count <= 7; count++ {
		for value := uint8(0); value <= paddingTableOffset[count]; value++ {
			table[paddingTableOffset[count]+value].padding = CompletePadding{bits: value, count: count}
		}
	}
	return table
}()

var paddingTableOffset = [8]uint8{0, 1, 3, 7, 15, 31, 63, 127}

func finalPaddingOf(padding CompletePadding) FinalPadding {
	if padding.bits == 0 || padding.count > 7 {
		return FinalPadding{}
	}
	first := paddingTableOffset[padding.count]
	if padding.bits > first {
		return FinalPadding{}
	}
	return FinalPadding{bits: &paddingTable[first+padding.bits]}
}

// Bits returns the stored terminal padding right-aligned and its width.
// Successful APER decoding returns (0, 0).
func (f FinalPadding) Bits() (value, count uint8) { return f.Padding().Bits() }

// Padding returns the stored terminal padding, which is zero after APER decoding.
func (f FinalPadding) Padding() CompletePadding {
	if f.bits == nil {
		return CompletePadding{}
	}
	return f.bits.padding
}

// Trailing returns an empty suffix. APER entry points reject trailing-bit
// tolerance; padding never carries such a suffix.
func (f FinalPadding) Trailing() TrailingBits { return TrailingBits{} }

// IsZero reports whether every stored padding bit is zero.
func (f FinalPadding) IsZero() bool { return f.bits == nil || f.bits.padding.IsZero() }

// CompleteBytesWithFinalPadding returns a complete encoding using the stored
// padding state (see CompleteBytesWithPadding). APER decoders leave that state
// zero, so their values encode with zero terminal padding (X.691 (02/2021)
// §11.1.4).
func (bb *BitBuffer) CompleteBytesWithFinalPadding(final FinalPadding) ([]byte, error) {
	if final.bits == nil {
		return bb.CompleteBytes(), nil
	}
	return bb.CompleteBytesWithPadding(final.bits.padding)
}
